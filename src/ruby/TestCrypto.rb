require 'openssl'

sha256 = OpenSSL::Digest::SHA256.new
HASH_INPUT_LENGTH = 1024
input = ""
for i in 0..HASH_INPUT_LENGTH
	input = input + (i % 256).to_s()
end 
digest = sha256.digest(input)
# puts digest.each_byte.map { |b| b.to\_s(16) }.join
puts digest