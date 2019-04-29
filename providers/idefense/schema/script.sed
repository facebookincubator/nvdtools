# remove the comment
s/^copy paste.*$//g

# fix first line to remove these weird signs
s/SearchResults«Vulnerability»/VulnerabilitySearchResults/g

# remove : Translatable
s/: Translatable.*$//g

# add the IDefense prefix to all types
s/(\W)Vulnerability/\1IDefenseVulnerability/g
s/^Vulnerability/IDefenseVulnerability/g

# create structs
s/^(\w+) \{/\n\/\/ \1 struct\ntype \1 struct \{/g

# convert types
s/boolean/bool/g
s/integer/int/g
s/number/float64/g

# IDefense.. -> *IDefense
s/IDefense/\*IDefense/g
s/type \*/type /g
s|// \*|// |g

# Array[type] -> []type
s/Array\[([\*A-Za-z0-9]+)\]/\[\]\1/g

# create struct fields
s/^([a-z0-9_]+) \(([]\*A-Za-z0-9\[]+), optional\),?/\u\1 \2 `json:"\1"`/g

# Run this a few times to convert underscores in field names to camel case
s/^(\S+)_(\w)/\1\u\2/g
s/^(\S+)_(\w)/\1\u\2/g
s/^(\S+)_(\w)/\1\u\2/g
s/^(\S+)_(\w)/\1\u\2/g

# fix some stuff manually
s/Uuid/UUID/g
s/Url/URL/g
s/Id(\W)/ID\1/g
