"""
Copyright 2018-2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
# import pytest
#
# from cfripper.rules.KMSKeyWildcardPrincipal import KMSKeyWildcardPrincipal
# from cfripper.model.result import Result
# from tests.utils import get_cfmodel_from

# TODO Implement check if this is needed as GenericWildcardPrincipal rule seems to include this one
# @pytest.fixture()
# def abcdef():
#     return get_cfmodel_from("rules/KMSKeyWildcardPrincipal/abcdef.json").resolve()
#
#
# def test_abcdef(abcdef):
#     result = Result()
#     rule = KMSKeyWildcardPrincipal(None, result)
#     rule.invoke(abcdef)
#
#     assert not result.valid
#     assert len(result.failed_rules) == 1
#     assert len(result.failed_monitored_rules) == 0
#     assert result.failed_rules[0]["rule"] == "KMSKeyWildcardPrincipal"
#     assert result.failed_rules[0]["reason"] == "KMS Key policy {} should not allow wildcard principals"
