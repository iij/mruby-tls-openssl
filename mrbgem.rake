require 'open3'
require 'fileutils'

MRuby::Gem::Specification.new('mruby-tls-openssl') do |spec|
  spec.license = 'MIT'
  spec.author  = 'Internet Initiative Japan Inc.'

  spec.add_dependency 'mruby-io'
  spec.add_dependency 'mruby-socket'

  openssl_dir = File.join(build_dir, "openssldir")
  openssl_source_dir =  File.join(build_dir, "openssl_src_dir")

  def run_command env, command
    STDOUT.sync = true
    puts "build: [exec] #{command}"
    Open3.popen2e(env, command) do |stdin, stdout, thread|
      print stdout.read
      fail "#{command} failed" if thread.value != 0
    end
  end

  def host_configure_option build
    return "" unless build.kind_of?(MRuby::CrossBuild)
    return "--host #{build.host_target}"
  end

  def flags_after_libraries build
    return "" unless build.kind_of?(MRuby::CrossBuild)
    return "-lws2_32" if build.host_target["w64"]
  end

  def build_dependency
    FileUtils.mkdir_p openssl_dir

    if !File.exists?(openssl_source_dir)
      Dir.chdir(build_dir) do
        e = {}
        run_command e, "git clone https://github.com/libressl-portable/portable.git #{openssl_source_dir}"
      end
    end

    if !File.exists?("#{openssl_dir}/lib/libssl.a")
      Dir.chdir(openssl_source_dir) do
        e = {
          'CC' => "#{spec.build.cc.command} #{spec.build.cc.flags.join(' ')}",
          'AR' => spec.build.archiver.command,
        }
        run_command e, "./autogen.sh" unless File.exists?("configure")
        run_command e, "./configure --disable-shared --prefix=\"#{openssl_dir}\" #{host_configure_option(spec.build)}"
        run_command e, "make"
        run_command e, "make install"
      end
    end
  end

  build_dependency if ENV["BUILD_SSL_DEPENDENCY"]

  spec.cc.include_paths << "#{openssl_dir}/include"
  spec.linker.library_paths << "#{openssl_dir}/lib"

  spec.linker.libraries << 'ssl'
  spec.linker.libraries << 'crypto'

  spec.linker.flags_after_libraries << flags_after_libraries(spec.build)
end
