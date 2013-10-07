#!/usr/bin/env ruby
# -*- coding: binary -*-
require 'rex/peparsey'
require 'openssl'

module Rex
module Authenticode

  SIGNED_DATA = "1.2.840.113549.1.7.2"
  CONTENT_TYPE = "1.2.840.113549.1.9.3"
  MESSAGE_DIGEST  = "1.2.840.113549.1.9.4"
  COUNTER_SIGNATURE = "1.2.840.113549.1.9.6"
  SPC_STATEMENT_TYPE = "1.3.6.1.4.1.311.2.1.11"
  SPC_SP_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12"
  SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15"
  INDIVIDUAL_CODE_SIGNING = "1.3.6.1.4.1.311.2.1.21"
  COMMERCIAL_CODE_SIGNING = "1.3.6.1.4.1.311.2.1.22"
  TIMESTAMP_COUNTER_SIGNATURE = "1.3.6.1.4.1.311.3.2.1"

  #http:#www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
# https:#github.com/mono/mono/blob/a31c107f59298053e4ff17fd09b2fa617b75c1ba/mcs/class/Mono.Security/Mono.Security.Authenticode/AuthenticodeFormatter.cs
  #https:#github.com/mono/mono/blob/a31c107f59298053e4ff17fd09b2fa617b75c1ba/mcs/class/Mono.Security/Mono.Security.Authenticode/AuthenticodeBase.cs
  class Formatter

  attr_accessor :authority, :certs, :crls, :hash, :rsa, :timestamp, :authenticode, :pkcs7, :description, :url
  def initialize(opts)
    self.authority = opts[:authority] || 'maximum'
    self.certs = opts[:certs] || [OpenSSL::X509::Certificate.new(File.read('/root/ia.crt'))]
    self.crls = opts[:crls]
    self.hash = opts[:hash] || OpenSSL::Digest::SHA1.new
    self.rsa = opts[:rsa] || OpenSSL::PKey::RSA.new(File.read('/root/ia.key'))
    self.timestamp = opts[:timestamp] || ''
    self.authenticode = opts[:authenticode]
    self.pkcs7 = opts[:pkcs7]
    self.description = opts[:description] || ''
    self.url = opts[:url] || ''
  end

  def sign(file)
    digest = GetHash(file)
    signature = Header(digest)
  end

  def GetHash(file)
    pe = Rex::PeParsey::Pe.new(Rex::ImageSource::Memory.new(file))
    dirSecurityOffset = pe.hdr.opt['DataDirectory'][Rex::PeParsey::PeBase::IMAGE_DIRECTORY_ENTRY_SECURITY]['VirtualAddress']
    dirSecuritySize = pe.hdr.opt['DataDirectory'][Rex::PeParsey::PeBase::IMAGE_DIRECTORY_ENTRY_SECURITY]['Size']

    # Check code from GetHash if we need to replace exes containing signatures already...

    pe_offset = pe.hdr.dos.e_lfanew
    # Start of file up to checksum
    checksum_offset = pe_offset + Rex::PeParsey::PeBase::IMAGE_FILE_HEADER_SIZE + 63
    hash.update(file[0,checksum_offset])
    # Skip Checksum
    offset = checksum_offset + 4
    # up to IMAGE_DIRECTORY_ENTRY_SECURITY offset
    ide_security = offset + 60
    hash.update(file[offset,ide_security])
    # Skip 8 bytes for ide_security
    offset = ide_security + 8

    hash.update(file[offset..-1])
    puts hash.digest.inspect

    return hash.digest
  end

  def Header(digest)
    obsolete = "\x03\x01\x00\xA0\x20\xA2\x1E\x80\x1C\x00\x3C\x00\x3C\x00\x3C\x00\x4F\x00\x62\x00\x73\x00\x6F\x00\x6C\x00\x65\x00\x74\x00\x65\x00\x3E\x00\x3E\x00\x3E"
    sha1_oid = "1.3.14.3.2.26" #no MD5 support yet
    spcPeImageData = OpenSSL::ASN1::ObjectId.new(SPC_PE_IMAGE_DATA)
    obs = OpenSSL::ASN1::BitString(obsolete)
    c1 = OpenSSL::ASN1::Sequence.new([spcPeImageData, obs])

    algorithm_identifier = OpenSSL::ASN1::ObjectId.new(sha1_oid)
    hash = OpenSSL::ASN1::OctetString.new(digest)
    c2 =  OpenSSL::ASN1::Sequence.new([algorithm_identifier, hash])
    content =  OpenSSL::ASN1::Sequence.new([c1,c2])

  end

end
end
end