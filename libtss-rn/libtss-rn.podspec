require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  # The npm package ships ios/LibtssFFI.xcframework and ios/include/libtss.h.
  # In a libtss checkout, create them with scripts/rn-ios-xcframework.sh.
  xcframework = File.expand_path("ios/LibtssFFI.xcframework", __dir__)
  unless File.exist?(xcframework)
    raise "libtss-rn: missing #{xcframework}; run scripts/rn-ios-xcframework.sh from the libtss repository"
  end

  s.name         = "libtss-rn"
  s.version      = package["version"]
  s.summary      = "React Native bindings for libtss"
  s.license      = { :type => "Apache-2.0 OR MIT" }
  s.author       = { "0xCarbon" => "contato@0xcarbon.org" }
  s.homepage     = "https://github.com/0xCarbon/libtss"
  s.platform     = :ios, "13.0"
  s.source       = { :path => "." }
  s.source_files = "ios/*.{h,m,mm}"
  s.requires_arc = true
  s.vendored_frameworks = "ios/LibtssFFI.xcframework"
  s.compiler_flags = "-Wall -Wextra"
  s.pod_target_xcconfig = {
    "HEADER_SEARCH_PATHS" => "$(inherited) \"$(PODS_TARGET_SRCROOT)/ios/include\""
  }
  s.frameworks = "Security"
  s.dependency "React-Core"
end
