# (C) Datadog, Inc. 2020-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
from collections import OrderedDict


def construct_xpath_query(filters):
    if not filters:
        return '*'

    node_tree = OrderedDict({'*': OrderedDict()})

    for node_path, values in filters.items():
        # We make `tree` reference the root of the tree
        # at every iteration to create the new branches.
        tree = node_tree['*']

        # Separate each full path into its constituent nodes.
        parts = node_path.split('.')

        # Recurse through all but the last node.
        for part in parts[:-1]:
            # Create branch if necessary.
            if part not in tree:
                tree[part] = OrderedDict()

            # Move to the next branch.
            tree = tree[part]

        # Set the final branch to the user-defined values.
        if values:
            tree[parts[-1]] = values
        # Users can define no values (indicating the mere presence of elements) with an empty list or mapping.
        # However, the parser assumes that values are always lists for simplicity.
        else:
            tree[parts[-1]] = []

    parts = []
    accumulate_query_parts(parts, node_tree)

    return ''.join(parts)


def accumulate_query_parts(parts, node_tree):
    # Due to time constraints, this here is an ugly parser. A cookie shall be given to the one who makes it beautiful.
    #
    # Here are a bunch of examples of XPath queries:
    # - https://powershell.org/2019/08/a-better-way-to-search-events/
    # - https://www.petri.com/query-xml-event-log-data-using-xpath-in-windows-server-2012-r2
    # - https://blog.backslasher.net/filtering-windows-event-log-using-xpath.html
    for node, values in node_tree.items():
        # Recursively walk the tree
        if isinstance(values, OrderedDict):
            if parts and parts[-1] == ']':
                parts.append(' and ')

            parts.append(node)
            parts.append('[')
            accumulate_query_parts(parts, values)

            # Catch erroneous operator
            if parts[-1] == ' and ':
                parts.pop()

            # Detect premature closures
            if parts[-1] is None:
                parts.pop()
            else:
                parts.append(']')

        # Finished branch
        else:
            if values:
                if parts and parts[-1] == ')':
                    parts.append(' and ')

                if node.startswith('@'):
                    parts.append(node)
                    parts.append(']=')
                    parts.append(value_to_xpath_string(values[0]))

                    # Indicate to the tree walker that we already closed the node
                    parts.append(None)
                else:
                    parts.append('(')
                    parts.append(' or '.join('{}={}'.format(node, value_to_xpath_string(value)) for value in values))
                    parts.append(')')
            else:
                if parts and parts[-1] == ']':
                    parts.append(' and ')

                parts.append(node)

                # Always assume more clauses and let tree walker catch errors
                parts.append(' and ')


def value_to_xpath_string(value):
    # Most sources indicate single quotes are preferred, I cannot find an official directive
    if isinstance(value, str):
        return "'{}'".format(value)

    return str(value)
