# (C) Datadog, Inc. 2020-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import win32api
import win32evtlog
from lxml import etree


class EventNamespace(object):
    # XML is a terrible format for data transmission; not everything is a document.
    #
    # Every event looks like this:
    #
    #   <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    #     <System>
    #       ...
    #     </System>
    #     <EventData>
    #       ...
    #     </EventData>
    #   </Event>
    #
    # The schema is defined here: https://docs.microsoft.com/en-us/windows/win32/wes/eventschema-eventtype-complextype
    #
    # The problem arises when accessing elements via tags in the presence of namespaces:
    #
    # - https://bugs.python.org/issue18304
    # - https://bugs.python.org/issue28238
    # - https://stackoverflow.com/q/4255277/5854007
    # - https://stackoverflow.com/q/13412496/5854007
    #
    # All the usual workarounds are garbage. Modification of the entire tree structure, string replacement
    # before parsing, iteration using string replacement, use of XPath queries, etc. are inefficient.
    #
    # What we do instead is dynamically create and cache full tag names so the parser can perform
    # constant-time lookups.

    def __init__(self, namespace):
        self.namespace = namespace

    def __getattr__(self, name):
        tag = self.namespace + name
        setattr(self, name, tag)
        return tag

    def strip(self, tag):
        return tag.replace(self.namespace, '', 1)


def parse_event_xml(event):
    # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender
    # http://timgolden.me.uk/pywin32-docs/win32evtlog__EvtRender_meth.html
    event_xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

    return etree.fromstring(event_xml)


def get_last_error_message():
    """
    Helper function to get the error message from the calling thread's most recently failed operation.

    It appears that in most cases pywin32 catches such failures and raises Python exceptions.
    """
    # https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
    # https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessage
    # http://timgolden.me.uk/pywin32-docs/win32api__FormatMessage_meth.html
    return win32api.FormatMessage(0)
