# (C) Datadog, Inc. 2020-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
from collections import OrderedDict

import pytest

from datadog_checks.win32_event_log.filters import construct_xpath_query


@pytest.mark.parametrize(
    'filters, query',
    [
        pytest.param(OrderedDict(), '*', id='no filters'),
        pytest.param(
            OrderedDict((('UserData/LowOnMemory', []),)),
            '*[UserData/LowOnMemory]',
            id='element selection only with list',
        ),
        pytest.param(
            OrderedDict((('UserData/LowOnMemory', {}),)),
            '*[UserData/LowOnMemory]',
            id='element selection only with dict',
        ),
        pytest.param(
            OrderedDict((('UserData.LowOnMemory', {}),)), '*[UserData[LowOnMemory]]', id='element selection path',
        ),
        pytest.param(
            OrderedDict((('System.EventID', [4624]),)),
            '*[System[(EventID=4624)]]',
            id='single root single node single value',
        ),
        pytest.param(
            OrderedDict((('System.Computer', ['HAL']),)),
            "*[System[(Computer='HAL')]]",
            id='single root single node single value string',
        ),
        pytest.param(
            OrderedDict((('System.Level', [1, 2]),)),
            '*[System[(Level=1 or Level=2)]]',
            id='single root single node multiple values',
        ),
        pytest.param(
            OrderedDict((('System.EventID', [4624]), ('System.Level', [1, 2]))),
            '*[System[(EventID=4624) and (Level=1 or Level=2)]]',
            id='single root multiple nodes mixed values',
        ),
        pytest.param(
            OrderedDict((('System.Level', [1, 2]), ('System.EventID', [4624]))),
            '*[System[(Level=1 or Level=2) and (EventID=4624)]]',
            id='single root multiple nodes preserve order',
        ),
        pytest.param(
            OrderedDict((('UserData/LowOnMemory', {}), ('System.Level', [1, 2]), ('System.EventID', [4624]))),
            '*[UserData/LowOnMemory and System[(Level=1 or Level=2) and (EventID=4624)]]',
            id='single root multiple nodes with element selection at beginning',
        ),
        pytest.param(
            OrderedDict((('System.Level', [1, 2]), ('System.EventID', [4624]), ('UserData/LowOnMemory', {}))),
            '*[System[(Level=1 or Level=2) and (EventID=4624)] and UserData/LowOnMemory]',
            id='single root multiple nodes with element selection at end',
        ),
        pytest.param(
            OrderedDict((('System.Level', [1, 2]), ('UserData/LowOnMemory', {}), ('System.EventID', [4624]))),
            '*[System[(Level=1 or Level=2) and (EventID=4624)] and UserData/LowOnMemory]',
            id='single root multiple nodes with element selection insertion same as at end',
        ),
        pytest.param(
            OrderedDict((('System/EventID', [4624]),)),
            '*[(System/EventID=4624)]',
            id='single root single node full path single value',
        ),
        pytest.param(
            OrderedDict((('System/Level', [1, 2]),)),
            '*[(System/Level=1 or System/Level=2)]',
            id='single root single node full path multiple values',
        ),
        pytest.param(
            OrderedDict((('System/Level', [1, 2]), ('System/EventID', [4624]))),
            '*[(System/Level=1 or System/Level=2) and (System/EventID=4624)]',
            id='single root multiple node full path mixed values',
        ),
        pytest.param(
            OrderedDict((("EventData.Data.@Name='TargetUserName'", ['Picard']),)),
            "*[EventData[Data[@Name='TargetUserName']='Picard']]",
            id='single root single node attribute selection',
        ),
        pytest.param(
            OrderedDict(
                (
                    ('System.Level', [1, 2]),
                    ('UserData/LowOnMemory', {}),
                    ('System.EventID', [4624]),
                    ("EventData.Data.@Name='TargetUserName'", ['Picard']),
                )
            ),
            (
                "*[System[(Level=1 or Level=2) and (EventID=4624)] and UserData/LowOnMemory and "
                "EventData[Data[@Name='TargetUserName']='Picard']]"
            ),
            id='compound query',
        ),
    ],
)
def test_query_construction(filters, query):
    assert construct_xpath_query(filters) == query
