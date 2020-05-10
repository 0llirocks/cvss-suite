require_relative '../spec_helper'

describe CvssSuite::Cvss3Helper do
  subject(:round_up) { described_class.round_up(float) }

  context 'without decimal places' do
    let(:float) { 2.0 }

    it 'should roundup by one decimal place' do
      expect(subject).to be(2.0)
    end
  end

  context 'with one decimal place' do
    let(:float) { 2.1 }

    it 'should roundup by one decimal place' do
      expect(subject).to be(2.1)
    end
  end

  context 'with two decimal place' do
    context 'with small part below 5' do
      let(:float) { 2.11 }

      it 'should roundup by one decimal place' do
        expect(subject).to be(2.2)
      end
    end

    context 'with small part above 5' do
      let(:float) { 2.19 }

      it 'should roundup by one decimal place' do
        expect(subject).to be(2.2)
      end
    end
  end

  context 'with three decimal place' do
    context 'with small part below 5' do
      let(:float) { 2.111 }

      it 'should roundup by one decimal place' do
        expect(subject).to be(2.2)
      end
    end

    context 'with small part above 5' do
      let(:float) { 2.199 }

      it 'should roundup by one decimal place' do
        expect(subject).to be(2.2)
      end
    end
  end

  context 'with long decimal place' do
    context 'round up hundred thousandths .000 01' do
      let(:float) { 2.00001 }

      it 'should roundup by one decimal place' do
        expect(subject).to be(2.1)
      end
    end

    context 'round up millionth .000 001' do
      let(:float) { 2.000001 }

      it 'should roundup by one decimal place' do
        expect(subject).to be(2.1)
      end
    end
  end
end
