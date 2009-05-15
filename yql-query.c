// yql-query.c
//
// ABOUT:
//   YQL command line frontend.
//
// AUTHOR:
//   Yasuhiro Matsumoto <mattn.jp@gmail.com>
//
// USAGE:
//   yql-query -f json "select * from html where url = 'http://example.com'"
//
// BUILD:
//   g++ yql-query.c -lxml2 -lcurl -ljson-c
//
//   for Windows:
//
//     cd c:\json-c-0.8
//
//     gcc -I. -c
//       arraylist.c 
//       debug.c
//       json_object.c
//       json_tokener.c
//       json_util.c
//       linkhash.c
//       printbuf.c
//
//     ar -r libjson-c.a *.o
//
//     g++ -Ic:/json-c-0.8 yql-query.c -lxml2 -lcurldll c:/json-c/libjson-c.a 

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <curl/curl.h>
namespace json {
#include "json.h"
}

typedef struct {
    char* data;  /* response data from server. */
    size_t size; /* response size of data.     */
} MEMFILE;

MEMFILE*
memfopen() {
    MEMFILE* mf = (MEMFILE*) malloc(sizeof(MEMFILE));
    if (!mf) return NULL;
    mf->data = NULL;
    mf->size = 0;
    return mf;
}

void
memfclose(MEMFILE* mf) {
    if (mf->data) free(mf->data);
    free(mf);
}

size_t
memfwrite(char* ptr, size_t size, size_t nmemb, void* stream) {
    MEMFILE* mf = (MEMFILE*) stream;
    int block = size * nmemb;
    if (!mf->data)
        mf->data = (char*)malloc(block);
    else
        mf->data = (char*)realloc(mf->data, mf->size + block);
    if (mf->data) {
        memcpy(mf->data + mf->size, ptr, block);
        mf->size += block;
    } else
        return (size_t)-1;
    return block;
}

char*
memfstrdup(MEMFILE* mf) {
    char* buf = (char*)malloc(mf->size + 1);
    if (!buf) return NULL;
    memcpy(buf, mf->data, mf->size);
    buf[mf->size + 1] = 0;
    return buf;
}

char* url_encode_alloc(const char* str, int force_encode) {
    const char* hex = "0123456789abcdef";

    char* buf = NULL;
    unsigned char* pbuf = NULL;
    int len = 0;

    if (!str) return NULL;
    len = strlen(str)*3;
    buf = (char*) malloc(len+1);
    if (!buf) return NULL;
    memset(buf, 0, len+1);
    pbuf = (unsigned char*)buf;
    while(*str) {
        unsigned char c = (unsigned char)*str;
        if (c == ' ')
            *pbuf++ = '+';
        else
        if (c & 0x80 || force_encode) {
            *pbuf++ = '%';
            *pbuf++ = hex[c >> 4];
            *pbuf++ = hex[c & 0x0f];
        } else
            *pbuf++ = c;
        str++;
    }
    return buf;
}

int opterr = 1;
int optind = 1;
int optopt;
char *optarg;

int getopt(int argc, char** argv, char* opts) {
    static int sp = 1;
    register int c;
    register char *cp;

    if (sp == 1) {
        if (optind >= argc
                || argv[optind][0] != '-' || argv[optind][1] == '\0')
            return EOF;
        else
        if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return EOF;
        }
    }
    optopt = c = argv[optind][sp];
    if (c == ':' || (cp = strchr(opts, c)) == NULL) {
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }
    if (*++cp == ':') {
        if (argv[optind][sp+1] != '\0') {
            optarg = &argv[optind++][sp+1];
        } else
        if (++optind >= argc) {
            sp = 1;
            return '?';
        } else
            optarg = argv[optind++];
        sp = 1;
    } else {
        if(argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }
    return c;
}

int
main(int argc, char* argv[]) {
    CURLcode res;
    CURL* curl;
    char error[CURL_ERROR_SIZE];
    MEMFILE* mf = NULL;
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr ctx = NULL;
    xmlXPathObjectPtr path = NULL;
    xmlBuffer* xmlbuf = NULL;
    char* buf = NULL;
    char* format = "xml";
    char* url = NULL;
    char* req = NULL;
    int c;

    opterr = 0;
    while ((c = getopt(argc, argv, "f:") != -1)) {
        switch (optopt) {
            case 'f':
                format = optarg;
                break;
            default:
                argc = 0;
                break;
        }
        optarg = NULL;
    }

    if ((argc - optind) != 1
            || (strcmp(format, "xml") && strcmp(format, "json"))) {
        fprintf(stderr, "%s: [-f xml/json] query", argv[0]);
        exit(1);
    }

    url = url_encode_alloc(argv[optind], TRUE);
    if (!url) {
        perror("failed to alloc memory");
        goto leave;
    }
    req = strdup("http://query.yahooapis.com/v1/public/yql?");
    req = (char*) realloc(req,
            strlen(req) + strlen(url) + strlen(format) + 11);
    if (!req) {
        perror("failed to alloc memory");
        goto leave;
    }
    strcat(req, "q=");
    strcat(req, url);
    strcat(req, "&format=");
    strcat(req, format);

    mf = memfopen();
    if (!mf) {
        perror("failed to alloc memory");
        goto leave;
    }

    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, &error);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, memfwrite);
    curl_easy_setopt(curl, CURLOPT_URL, req);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, mf);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, error);
        goto leave;
    }
    curl_easy_cleanup(curl);
    buf = memfstrdup(mf);
    if (!buf) {
        perror("failed to alloc memory");
        goto leave;
    }

    if (!strcmp(format, "json")) {
        json::json_object *obj;
        json::mc_set_debug(1);
        obj = json::json_tokener_parse(buf);
        if (obj && !is_error(obj)) {
            json::json_object *query, *result;
            query = json::json_object_object_get(obj, "query");
            if (query && !is_error(query)) {
                result = json::json_object_object_get(query, "results");
                if (result && !is_error(result)) {
                    printf("%s\n", json::json_object_to_json_string(result));
                    json_object_put(result);
                }
                json_object_put(query);
            } else {
                json::json_object *error, *description;
                error = json::json_object_object_get(obj, "error");
                if (error && !is_error(error)) {
                    description = json::json_object_object_get(
                            error, "description");
                    if (description && !is_error(description)) {
                        fprintf(stderr, "%s\n",
                                json::json_object_get_string(description));
                        json_object_put(description);
                    }
                    json_object_put(error);
                }
            }
        }
    } else
        if (!strcmp(format, "xml")) {
            doc = xmlParseDoc((xmlChar*)buf);
            if (!doc) goto leave;
            ctx = xmlXPathNewContext(doc);
            if (!ctx) goto leave;
            path = xmlXPathEvalExpression((xmlChar*)"/query/results", ctx);
            if (!path) goto leave;
            if (xmlXPathNodeSetGetLength(path->nodesetval) != 1) {
                path = xmlXPathEvalExpression(
                        (xmlChar*)"/error/description", ctx);
                if (!path) goto leave;
                if (xmlXPathNodeSetGetLength(path->nodesetval) != 1) goto leave;

                node = path->nodesetval->nodeTab[0];
                fprintf(stderr, "%s\n", node->children->content);
                goto leave;
            }

            node = path->nodesetval->nodeTab[0];
            xmlbuf = xmlBufferCreate();
            xmlNodeDump(xmlbuf, doc, node, 0, 1);
            printf("%s\n", xmlBufferContent(xmlbuf));
        }

leave:
    if (url) free(url);
    if (req) free(req);
    if (mf) memfclose(mf);
    if (buf) free(buf);
    if (xmlbuf) xmlBufferFree(xmlbuf);
    if (ctx) xmlXPathFreeContext(ctx);
    if (path) xmlXPathFreeObject(path);
    if (doc) xmlFreeDoc(doc);
    return 0;
}
// vim: set et:
