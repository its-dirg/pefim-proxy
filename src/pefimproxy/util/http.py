__author__ = 'haho0032'
from StringIO import StringIO
import json
from urlparse import parse_qs


class Session(object):
    BEAKER = 'beaker.session'

    def __init__(self, environ):
        self.environ = environ

    def clear_session(self):
        session = self.environ[Session.BEAKER]
        for key in session:
            session.pop(key, None)
        session.save()

    def __setitem__(self, item, val):
        if item not in self.environ[Session.BEAKER]:
            self.environ[Session.BEAKER].get(item, val)
        self.environ[Session.BEAKER][item] = val

    def __getitem__(self, item):
        return self.environ[Session.BEAKER].get(item, None)

    def __contains__(self, item):
        return item in self.environ[Session.BEAKER]


class HttpHelper(object):

    @staticmethod
    def query_dictionary(environ):
        """
        Retrieves a dictionary with query parameters.
        Does not matter if the query parameters are POST or GET.
        Can handle JSON and URL encoded POST, otherwise the body is returned in a dictionare with the key post.
        :param environ: The wsgi enviroment.
        :return: A dictionary with query parameters.
        """
        qs = {}
        query = environ.get("QUERY_STRING", "")
        if not query:
            try:
                length = int(environ["CONTENT_LENGTH"])
                body = environ["wsgi.input"].read(length)
                environ['wsgi.input'] = StringIO(body)
                if "CONTENT_TYPE" in environ and "application/json" in environ["CONTENT_TYPE"]:
                    return json.loads(body)
                elif "CONTENT_TYPE" in environ and environ["CONTENT_TYPE"] == "application/x-www-form-urlencoded":
                    return parse_qs(body)
                else:
                    return {"post": body}
            except:
                pass

        else:
            qs = dict((k, v if len(v) > 1 else v[0]) for k, v in
                      parse_qs(query).iteritems())
        return qs

    @staticmethod
    def log_request(environ, path, logger):
        """
        Logs the WSGI request.
        """
        query = HttpHelper.query_dictionary(environ)
        if "CONTENT_TYPE" in environ:
            logger.info("CONTENT_TYPE:" + environ["CONTENT_TYPE"])
        if "REQUEST_METHOD" in environ:
            logger.info("CONTENT_TYPE:" + environ["REQUEST_METHOD"])
        logger.info("Path:" + path)
        logger.info("Query:")
        logger.info(query)

    @staticmethod
    def handle_static(path, base_dir, start_response, logger):
        """
        Renders static pages.
        :param path: Requested resource.
        :return: WSGI response.
        """

        if path.startswith("static/") or "robots.txt" in path:
            if "robots.txt" in path:
                path = "static/robots.txt"
            ending = '.' + path[::-1].split('.')[0][::-1]
            text = open(base_dir + path).read()
            if ending == ".ico":
                start_response('200 OK', [('Content-Type', "image/x-icon")])
            elif ending == ".html":
                start_response('200 OK', [('Content-Type', 'text/html')])
            elif ending == ".json":
                start_response('200 OK', [('Content-Type', 'application/json')])
            elif ending == ".txt":
                start_response('200 OK', [('Content-Type', 'text/plain')])
            elif ending == ".css":
                start_response('200 OK', [('Content-Type', 'text/css')])
            elif ending == ".js":
                start_response('200 OK', [('Content-Type', 'text/javascript')])
            elif ending == ".xml":
                start_response('200 OK', [('Content-Type', 'text/xml')])
            else:
                raise Exception
            logger.info("[static]sending: %s" % (path,))
            return [text]
        raise Exception
