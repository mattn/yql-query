all : yql-query
	@echo done

yql-query : yql-query.c
	g++ -Wall -g `pkg-config --cflags --libs libxml-2.0` -o yql-query yql-query.c -lxml2 -lcurl
