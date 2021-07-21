require 'spec_helper_acceptance'

describe 'certs::foreman' do
  fqdn = fact('fqdn')

  context 'with default parameters' do
    it_behaves_like 'an idempotent resource' do
      let(:manifest) do
       <<~MANIFEST
         class { 'certs::foreman':
           client_cert           => '/tmp/foreman_client_cert.pem',
           client_key            => '/tmp/foreman_client_key.pem',
           ssl_ca_cert           => '/tmp/foreman_proxy_ca.pem',
           owner                 => 'root',
           group                 => 'root',
         }
        MANIFEST
      end
    end

    describe x509_certificate('/tmp/foreman_client_cert.pem') do
      it { should be_certificate }
      it { should be_valid }
      it { should have_purpose 'client' }
      its(:issuer) { should eq("C = US, ST = North Carolina, L = Raleigh, O = Katello, OU = SomeOrgUnit, CN = #{fqdn}") }
      its(:subject) { should eq("C = US, ST = North Carolina, O = FOREMAN, OU = PUPPET, CN = #{fqdn}") }
      its(:keylength) { should be >= 4096 }
    end

    describe file('/tmp/foreman_client_cert.pem') do
      it { should be_file }
      it { should be_mode 440 }
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
    end

    describe x509_private_key('/tmp/foreman_client_key.pem') do
      it { should_not be_encrypted }
      it { should be_valid }
      it { should have_matching_certificate('/tmp/foreman_client_cert.pem') }
    end

    describe file('/tmp/foreman_client_key.pem') do
      it { should be_file }
      it { should be_mode 440 }
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
    end

    describe x509_certificate('/tmp/foreman_proxy_ca.pem') do
      it { should be_certificate }
      it { should be_valid }
      its(:issuer) { should eq("C = US, ST = North Carolina, L = Raleigh, O = Katello, OU = SomeOrgUnit, CN = #{fqdn}") }
      its(:subject) { should eq("C = US, ST = North Carolina, L = Raleigh, O = Katello, OU = SomeOrgUnit, CN = #{fqdn}") }
      its(:keylength) { should be >= 4096 }
    end

    describe x509_certificate("/root/ssl-build/#{fqdn}/#{fqdn}-foreman-client.crt") do
      it { should be_certificate }
      it { should be_valid }
      it { should have_purpose 'client' }
      its(:issuer) { should eq("C = US, ST = North Carolina, L = Raleigh, O = Katello, OU = SomeOrgUnit, CN = #{fqdn}") }
      its(:subject) { should eq("C = US, ST = North Carolina, O = FOREMAN, OU = PUPPET, CN = #{fqdn}") }
      its(:keylength) { should be >= 4096 }
    end

    describe x509_private_key("/root/ssl-build/#{fqdn}/#{fqdn}-foreman-client.key") do
      it { should_not be_encrypted }
      it { should be_valid }
      it { should have_matching_certificate("/root/ssl-build/#{fqdn}/#{fqdn}-foreman-client.crt") }
    end
  end
end
