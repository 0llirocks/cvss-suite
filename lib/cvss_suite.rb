# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2016
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require 'cvss_suite/cvss2/cvss2'
require 'cvss_suite/cvss3/cvss3'
require 'cvss_suite/version'
require 'cvss_suite/helpers/extensions'
require 'cvss_suite/errors'
require 'cvss_suite/invalid_cvss'

##
# Module of this gem.

module CvssSuite
  CVSS_VECTOR_BEGINNINGS = [{:string => 'AV:', :version => 2}, {:string => 'CVSS:3.0/', :version => 3}]

  ##
  # Returns a CVSS class by a +vector+.

  def self.new(vector)
    @vector_string = vector
    case version
    when 2
      Cvss2.new(@vector_string, version)
    when 3
      Cvss3.new(@vector_string, version)
    else
      InvalidCvss.new
    end
  end

  private

  def self.version
    CVSS_VECTOR_BEGINNINGS.each do |beginning|
      if @vector_string.start_with? beginning[:string]
        return beginning[:version]
      end
    end
  end

end
