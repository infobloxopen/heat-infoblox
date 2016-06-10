# Copyright 2016 Infoblox Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


def create_side_effect(values):
    def dict_side_effect(key):
        if key in values:
            return values[key]
        else:
            return None
    if isinstance(values, dict):
        return dict_side_effect
    elif hasattr(values, '__iter__'):
        return values
    else:
        return (values)
