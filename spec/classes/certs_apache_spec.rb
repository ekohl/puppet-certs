require 'spec_helper'

describe 'certs::apache' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let :facts do
        os_facts
      end

      describe 'with default parameters' do
        it { is_expected.to compile.with_all_deps }
      end

      describe 'with group overridden' do
        let :pre_condition do
          "class {'certs': group => 'foreman',}"
        end

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_certs__keypair('apache')
            .with_key_group('foreman')
        end
      end
    end
  end
end
