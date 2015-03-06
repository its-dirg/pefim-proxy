# -*- coding:utf-8 -*-
from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 9
_modified_time = 1425656786.893183
_enable_loop = True
_template_filename = 'mako/htdocs/bad_request.mako'
_template_uri = 'bad_request.mako'
_source_encoding = 'utf-8'
_exports = [u'headline', u'body', u'title']


def _mako_get_namespace(context, name):
    try:
        return context.namespaces[(__name__, name)]
    except KeyError:
        _mako_generate_namespaces(context)
        return context.namespaces[(__name__, name)]
def _mako_generate_namespaces(context):
    pass
def _mako_inherit(template, context):
    _mako_generate_namespaces(context)
    return runtime._inherit_from(context, u'base.mako', _template_uri)
def render_body(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        def headline():
            return render_headline(context._locals(__M_locals))
        def body():
            return render_body(context._locals(__M_locals))
        log_id = context.get('log_id', UNDEFINED)
        parent = context.get('parent', UNDEFINED)
        def title():
            return render_title(context._locals(__M_locals))
        __M_writer = context.writer()
        # SOURCE LINE 1
        __M_writer(u'<!DOCTYPE html>\n')
        # SOURCE LINE 2
        __M_writer(u'\n\n')
        if 'parent' not in context._data or not hasattr(context._data['parent'], 'title'):
            context['self'].title(**pageargs)
        

        # SOURCE LINE 7
        __M_writer(u'\n\n')
        if 'parent' not in context._data or not hasattr(context._data['parent'], 'headline'):
            context['self'].headline(**pageargs)
        

        # SOURCE LINE 16
        __M_writer(u'\n\n')
        if 'parent' not in context._data or not hasattr(context._data['parent'], 'body'):
            context['self'].body(**pageargs)
        

        return ''
    finally:
        context.caller_stack._pop_frame()


def render_headline(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        def headline():
            return render_headline(context)
        __M_writer = context.writer()
        # SOURCE LINE 9
        __M_writer(u'\n    <!-- Static navbar -->\n    <nav class="navbar navbar-default" role="navigation">\n        <div class="navbar-header">\n          <a class="navbar-brand" href="#">Bad request</a>\n        </div>\n    </nav>\n')
        return ''
    finally:
        context.caller_stack._pop_frame()


def render_body(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        def body():
            return render_body(context)
        log_id = context.get('log_id', UNDEFINED)
        __M_writer = context.writer()
        # SOURCE LINE 18
        __M_writer(u'\n        <div class="row" style="text-align: center">\n            <div class="col-lg-12">Your request can not be handled by the identity server.</div>\n        </div>\n        <div class="row" style="text-align: center">\n            <div class="col-lg-12">Please contact the technical support for the service you are trying to get access to.</div>\n        </div>\n        <div class="row" style="text-align: center">\n            <div class="col-lg-12">Please state this id to your support: ')
        # SOURCE LINE 26
        __M_writer(unicode(log_id))
        __M_writer(u'</div>\n        </div>\n\n')
        return ''
    finally:
        context.caller_stack._pop_frame()


def render_title(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        parent = context.get('parent', UNDEFINED)
        def title():
            return render_title(context)
        __M_writer = context.writer()
        # SOURCE LINE 4
        __M_writer(u'\n    Bad request\n    ')
        # SOURCE LINE 6
        __M_writer(unicode(parent.title()))
        __M_writer(u'\n')
        return ''
    finally:
        context.caller_stack._pop_frame()


