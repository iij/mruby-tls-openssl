MRuby::Gem::Specification.new('mruby-tls-openssl') do |spec|
  spec.license = 'MIT'
  spec.author  = 'Internet Initiative Japan'

  spec.add_dependency 'mruby-io'
  spec.add_dependency 'mruby-socket'

  spec.cc.include_paths << "#{spec.dir}/openssldir/include"
  spec.linker.library_paths << "#{spec.dir}/openssldir/lib"

  spec.linker.libraries << 'ssl'
  spec.linker.libraries << 'crypto'
end
