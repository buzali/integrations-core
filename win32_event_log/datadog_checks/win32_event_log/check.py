# (C) Datadog, Inc. 2020-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
from itertools import chain

import win32con
import win32event
import win32evtlog

from datadog_checks.base import AgentCheck, ConfigurationError, is_affirmative

from .compat import read_persistent_cache, write_persistent_cache
from .filters import construct_xpath_query
from .legacy import Win32EventLogWMI
from .utils import EventNamespace, parse_event_xml


class Win32EventLogCheck(AgentCheck):
    # https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_subscribe_flags
    START_OPTIONS = {
        'now': win32evtlog.EvtSubscribeToFutureEvents,
        'oldest': win32evtlog.EvtSubscribeStartAtOldestRecord,
    }

    # https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_rpc_login_flags
    LOGIN_FLAGS = {
        'default': win32evtlog.EvtRpcLoginAuthDefault,
        'negotiate': win32evtlog.EvtRpcLoginAuthNegotiate,
        'kerberos': win32evtlog.EvtRpcLoginAuthKerberos,
        'ntlm': win32evtlog.EvtRpcLoginAuthNTLM,
    }

    def __new__(cls, name, init_config, instances):
        instance = instances[0]

        if is_affirmative(instance.get('legacy_mode', True)):
            return Win32EventLogWMI(name, init_config, instances)
        else:
            return super(Win32EventLogCheck, cls).__new__(cls)

    def __init__(self, name, init_config, instances):
        super(Win32EventLogCheck, self).__init__(name, init_config, instances)

        # Event channel or log file with which to subscribe
        self._path = self.instance.get('path', '')

        # The point at which to start the event subscription
        self._subscription_start = self.instance.get('start', 'now')

        # Raw user-defined query or one we construct based on filters
        self._query = None

        # Create a pull subscription and its signaler on the first check run
        self._subscription = None
        self._event_handle = None

        # Create a bookmark handle which will be updated on saves to disk
        self._bookmark_handle = None

        # Session used for remote connections, or None if local connection
        self._session = None

        # Connection options
        self._timeout = int(float(self.instance.get('timeout', 5)) * 1000)
        self._payload_size = int(self.instance.get('payload_size', 10))

        # How often to update the cached bookmark
        self._bookmark_frequency = int(self.instance.get('bookmark_frequency', self._payload_size))

        self.check_initializations.append(self.parse_config)
        self.check_initializations.append(self.construct_query)
        self.check_initializations.append(self.create_session)
        self.check_initializations.append(self.create_subscription)

    def check(self, _):
        events, ns = self.get_events_and_namespace()
        if events is None:
            return

        for event in events:
            root = parse_event_xml(event)
            return root

    def pull_events(self):
        # Define out here and let loop shadow so we can update the bookmark one final time at the end of the check run
        event = None

        events_since_last_bookmark = 0
        while True:

            # IMPORTANT: the subscription starts immediately so you must consume before waiting for the first signal
            while True:
                # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext
                # http://timgolden.me.uk/pywin32-docs/win32evtlog__EvtNext_meth.html
                events = win32evtlog.EvtNext(self._subscription, self._payload_size)
                if not events:
                    break

                for event in events:
                    events_since_last_bookmark += 1
                    if events_since_last_bookmark >= self._bookmark_frequency:
                        events_since_last_bookmark = 0
                        self.update_bookmark(event)

                    yield event

            # https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobjectex
            # http://timgolden.me.uk/pywin32-docs/win32event__WaitForSingleObjectEx_meth.html
            wait_signal = win32event.WaitForSingleObjectEx(self._event_handle, self._timeout, True)

            # No more events, end check run
            if wait_signal != win32con.WAIT_OBJECT_0:
                break

        if events_since_last_bookmark:
            self.update_bookmark(event)

    def update_bookmark(self, event):
        win32evtlog.EvtUpdateBookmark(self._bookmark_handle, event)
        bookmark = win32evtlog.EvtRender(self._bookmark_handle, win32evtlog.EvtRenderBookmark)

        self.write_persistent_cache('bookmark', bookmark)

    def parse_config(self):
        if not self._path:
            raise ConfigurationError('You must select a `path`.')

        if self._subscription_start not in self.START_OPTIONS:
            raise ConfigurationError('Option `start` must be one of: {}'.format(', '.join(sorted(self.START_OPTIONS))))

        password = self.instance.get('password')
        if password:
            self.register_secret(password)

    def construct_query(self):
        query = self.instance.get('query')
        if query:
            self._query = query
            return

        filters = self.instance.get('filters', {})
        if not isinstance(filters, dict):
            raise ConfigurationError('The `filters` option must be a mapping.')

        for key, value in filters.items():
            if not isinstance(value, list) or not (isinstance(value, dict) and not value):
                raise ConfigurationError('Value for event filter `{}` must be an array or empty mapping.'.format(key))

        self._query = construct_xpath_query(filters)

    def create_session(self):
        session_struct = self.get_session_struct()

        # No need for a remote connection
        if session_struct is None:
            return

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtopensession
        # http://timgolden.me.uk/pywin32-docs/win32evtlog__EvtOpenSession_meth.html
        self._session = win32evtlog.EvtOpenSession(session_struct, win32evtlog.EvtRpcLogin, 0, 0)

    def create_subscription(self):
        # https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa
        # http://timgolden.me.uk/pywin32-docs/win32event__CreateEvent_meth.html
        self._event_handle = win32event.CreateEvent(None, 0, 0, self.check_id)

        bookmark = self.read_persistent_cache('bookmark')
        if bookmark:
            flags = win32evtlog.EvtSubscribeStartAfterBookmark
        else:
            flags = self.START_OPTIONS[self._subscription_start]

            # Set explicitly to None rather than a potentially empty string
            bookmark = None

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtcreatebookmark
        # http://timgolden.me.uk/pywin32-docs/win32evtlog__EvtCreateBookmark_meth.html
        self._bookmark_handle = win32evtlog.EvtCreateBookmark(bookmark)

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe
        # http://timgolden.me.uk/pywin32-docs/win32evtlog__EvtSubscribe_meth.html
        self._subscription = win32evtlog.EvtSubscribe(
            self._path,
            flags,
            SignalEvent=self._event_handle,
            Query=self._query,
            Session=self._session,
            Bookmark=self._bookmark_handle if bookmark else None,
        )

    def get_session_struct(self):
        server = self.instance.get('server', 'localhost')
        if server == 'localhost':
            return

        auth_type = self.instance.get('auth_type', 'default')
        if auth_type not in self.LOGIN_FLAGS:
            raise ConfigurationError('Invalid `auth_type`, must be one of: {}'.format(' | '.join(self.LOGIN_FLAGS)))

        user = self.instance.get('user')
        domain = self.instance.get('domain')
        password = self.instance.get('password')

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/ns-winevt-evt_rpc_login
        # http://timgolden.me.uk/pywin32-docs/PyEVT_RPC_LOGIN.html
        return server, user, domain, password, self.LOGIN_FLAGS[auth_type]

    def get_events_and_namespace(self):
        events = self.pull_events()

        try:
            first_event = next(events)
        except StopIteration:
            return None, None

        # We must parse the first event twice, no great way around this
        root = parse_event_xml(first_event)

        # It's unlikely that the schema manifest will change but we do this to be future-proof. See:
        # https://docs.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest
        namespace = root.nsmap.get(None, '')
        if namespace:
            namespace = '{{{}}}'.format(namespace)

        return chain((first_event,), events), EventNamespace(namespace)

    def read_persistent_cache(self, key):
        return read_persistent_cache(self.check_id + key)

    def write_persistent_cache(self, key, value):
        write_persistent_cache(self.check_id + key, value)
