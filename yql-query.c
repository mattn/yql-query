// yql-query.c
//
// ABOUT:
//   YQL command line frontend.
//
// AUTHOR:
//   Yasuhiro Matsumoto <mattn.jp@gmail.com>
//
// USAGE:
//   yql-query -f xml "select * from html where url = 'http://example.com'"
//   yql-query -f json "select * from html where url = 'http://example.com'"
//   yql-query -f json -u http://datatables.org/alltables.env "select * from github.user.info where id='mattn'"
//
// BUILD:
//   g++ yql-query.c -lxml2 -lcurl
//

#include <memory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <curl/curl.h>
#include "picojson.h"

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

char* url_encode_alloc(const char* str, bool force_encode) {
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

int getopt(int argc, char** argv, const char* opts) {
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
    const char* format = "xml";
    char* userenv = NULL;
    char* url = NULL;
    int len = 0;
    char* req = NULL;
    int c;

    opterr = 0;
    while ((c = getopt(argc, argv, "f:u:") != -1)) {
        switch (optopt) {
            case 'f':
                format = optarg;
                break;
            case 'u':
                userenv = optarg;
                break;
            default:
                argc = 0;
                break;
        }
        optarg = NULL;
    }

    if ((argc - optind) != 1
            || (strcmp(format, "xml") && strcmp(format, "json"))) {
        std::cerr << argv[0] << ": [-f xml/json] [-u] query" << std::endl;
        exit(1);
    }

    url = url_encode_alloc(argv[optind], true);
    if (!url) {
        perror("failed to alloc memory");
        goto leave;
    }
    if (userenv) {
        userenv = url_encode_alloc(userenv, true);
        if (!userenv) {
            perror("failed to alloc memory");
            goto leave;
        }
    }

    req = strdup("http://query.yahooapis.com/v1/public/yql?");
    len = strlen(req) + 2 + strlen(url) + 8 + strlen(format) + 1;
    if (userenv) {
        len += 5 + strlen(userenv);
    }
    req = (char*) realloc(req, len);
    if (!req) {
        perror("failed to alloc memory");
        goto leave;
    }
    strcat(req, "q=");
    strcat(req, url);
    strcat(req, "&format=");
    strcat(req, format);
    if (userenv) {
        strcat(req, "&env=");
        strcat(req, userenv);
    }

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
        std::cerr << error << std::endl;
        goto leave;
    }
    curl_easy_cleanup(curl);

    if (!strcmp(format, "json")) {
        picojson::value v;
        std::string err;
        picojson::parse(v, mf->data, mf->data + mf->size, &err);
        if (err.empty() && v.is<picojson::object>()) {
            picojson::value vv = v.get<picojson::object>()["query"];
            if (vv.is<picojson::object>())
                std::cerr << vv.get<picojson::object>()["results"].serialize() << std::endl;
            else {
                vv = v.get<picojson::object>()["error"];
                if (vv.is<picojson::object>())
                    std::cout << vv.get<picojson::object>()["description"].to_str().c_str() << std::endl;
                else
                    std::cerr << "unknown error" << std::endl;
            }
        }
    } else
    if (!strcmp(format, "xml")) {
        doc = xmlParseMemory(mf->data, mf->size);
        if (!doc) goto leave;
        ctx = xmlXPathNewContext(doc);
        if (!ctx) goto leave;
        path = xmlXPathEvalExpression((xmlChar*)"/query/results", ctx);
        if (!path || xmlXPathNodeSetGetLength(path->nodesetval) == 0) {
            path = xmlXPathEvalExpression(
                    (xmlChar*)"/error/description", ctx);
            if (!path) goto leave;
            if (xmlXPathNodeSetGetLength(path->nodesetval) != 1) goto leave;
            node = path->nodesetval->nodeTab[0];
            std::cerr << node->children->content << std::endl;
            goto leave;
        }
        if (xmlXPathNodeSetGetLength(path->nodesetval) != 0) {
            node = path->nodesetval->nodeTab[0];
            xmlbuf = xmlBufferCreate();
            xmlNodeDump(xmlbuf, doc, node, 0, 1);
            std::cout << xmlBufferContent(xmlbuf) << std::endl;
        }
    }

leave:
    if (url) free(url);
    if (req) free(req);
    if (userenv) free(userenv);
    if (mf) memfclose(mf);
    if (xmlbuf) xmlBufferFree(xmlbuf);
    if (ctx) xmlXPathFreeContext(ctx);
    if (path) xmlXPathFreeObject(path);
    if (doc) xmlFreeDoc(doc);
    return 0;
}
// vim: set et:
