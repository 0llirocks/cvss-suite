require 'spec_helper'

describe Cvss do

    let(:valid_cvss2) { Cvss.new('AV:N/AC:L/Au:S/C:P/I:P/C:P/AV:U/RL:OF/RC:C') }
    let(:invalid_cvss2) { Cvss.new('AV:N/AC:P/C:P/AV:U/RL:OF/RC:C') }
    let(:valid_cvss3) { Cvss.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L/E:U/RL:W/RC:R') }
    let(:invalid_cvss3) { Cvss.new('CVSS:3.0/AV:L/AC:') }

    describe 'valid cvss2' do
      subject { valid_cvss2 }

      it { should be_valid }
      its(:version) { should eql(2) }
    end

    describe 'invalid cvss2' do
      subject { invalid_cvss2 }

      it { should_not be_valid }
      its(:version) { should raise_error('Vector is not valid!') }
    end

    describe 'valid cvss3' do
      subject { valid_cvss3 }

      it { should be_valid }
      its(:version) { should eql(3) }
    end

    describe 'invalid cvss3' do
      subject { invalid_cvss3 }

      it { should_not be_valid }
      its(:version) { should raise_error('Vector is not valid!') }
    end
end