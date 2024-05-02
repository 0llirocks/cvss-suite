class String
    def truncate(truncate_to)
        return dup unless length > truncate_to
    
        "#{self[0, truncate_to + 1]}"
    end
end