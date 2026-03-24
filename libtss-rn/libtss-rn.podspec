Pod::Spec.new do |s|
  # --- Bundled path (npm-published layout) ---
  bundled_device_lib = File.expand_path("ios/libs/aarch64-apple-ios/liblibtss_ffi.a", __dir__)
  bundled_sim_lib = File.expand_path("ios/libs/aarch64-apple-ios-sim/liblibtss_ffi.a", __dir__)

  # --- Workspace path (local development) ---
  workspace_device_lib = File.expand_path("../target/aarch64-apple-ios/release/liblibtss_ffi.a", __dir__)
  workspace_sim_lib = File.expand_path("../target/aarch64-apple-ios-sim/release/liblibtss_ffi.a", __dir__)

  if File.exist?(bundled_device_lib)
    ios_device_lib = bundled_device_lib
    ios_simulator_lib = bundled_sim_lib
    header_search_path = "\"$(PODS_TARGET_SRCROOT)/ios/include\""
  else
    ios_device_lib = workspace_device_lib
    ios_simulator_lib = workspace_sim_lib
    header_search_path = "\"$(PODS_TARGET_SRCROOT)/../libtss-ffi\""
  end

  s.name         = "libtss-rn"
  s.version      = "0.1.0"
  s.summary      = "React Native bindings for libtss"
  s.license      = { :type => "Apache-2.0 OR MIT" }
  s.author       = { "0xCarbon" => "contato@0xcarbon.org" }
  s.platform     = :ios, "13.0"
  s.source       = { :path => "." }
  s.source_files = "ios/*.{h,m,mm}"
  s.requires_arc = true
  s.pod_target_xcconfig = {
    "HEADER_SEARCH_PATHS" => "$(inherited) #{header_search_path}",
    "LIBRARY_SEARCH_PATHS[sdk=iphoneos*]" => "$(inherited) \"#{File.dirname(ios_device_lib)}\"",
    "LIBRARY_SEARCH_PATHS[sdk=iphonesimulator*]" => "$(inherited) \"#{File.dirname(ios_simulator_lib)}\"",
    "OTHER_LDFLAGS" => "$(inherited) -llibtss_ffi"
  }
  s.frameworks = "Security"
  s.dependency "React-Core"
end
