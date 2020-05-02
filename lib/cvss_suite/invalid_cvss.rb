# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2018
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

# ##
# # This class represents a invalid CVSS vector.

module CvssSuite
  class InvalidCvss < Cvss
    ##
    # Creates a new invalid CVSS vector.

    def initialize; end

    ##
    # Since this is an invalid CVSS vector, it always returns false.

    def valid?
      false
    end

    ##
    # Since this is an invalid CVSS vector, it always throws an exception.

    def version
      check_validity
    end

    ##
    # Since this is an invalid CVSS vector, it always throws an exception.

    def base_score
      check_validity
    end

    ##
    # Since this is an invalid CVSS vector, it always throws an exception.

    def temporal_score
      check_validity
    end

    ##
    # Since this is an invalid CVSS vector, it always throws an exception.

    def environmental_score
      check_validity
    end
  end
end
