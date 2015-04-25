#
# Cookbook Name:: winsecurity
# Recipe:: default
#
# Copyright (C) 2015 Chef Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

control_group 'registry keys' do

  control 'system security hive' do
    let(:registry_key) { windows_registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') }

    it 'should not allow shutdown without logon' do
      expect(registry_key).to have_property_value('ShutdownWithoutLogon', :type_dword, '0')
    end

    # Expected to fail with a default install
    it 'should have legal notices' do
      expect(registry_key).to have_property_value('legalnoticecaption', :type_string, 'WARNING')
      expect(registry_key).to have_property_value('legalnoticetext', :type_string, 'This system is the property of Chef Software, Inc. Unauthorized use will result in prosecution.')
    end
  end
end

control_group 'services' do
  control 'firewall' do
    let(:firewall) { service('MpsSvc') }
    it 'should have the firewall enabled' do
      expect(firewall).to be_enabled
      expect(firewall).to be_running
      expect(firewall).to have_start_mode('Automatic')
    end
  end
end
