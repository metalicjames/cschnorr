newoption {
    trigger = "lib-dir",
    description = "Specify extra directory to look for libraries in",
    value = "DIR"
}

newoption {
    trigger = "include-dir",
    description = "Specify extra directory to look for headers in",
    value = "DIR"
}

workspace "cschnorr"
    configurations {"Debug", "Release"}
    platforms {"Static", "Shared"}
    language "C"
    includedirs {_OPTIONS["include-dir"]}
    libdirs {_OPTIONS["lib-dir"]}

    filter {"configurations:Debug"}
        optimize "Off"
        symbols "On"

    filter {"configurations:Release"}
        optimize "Full"
        symbols "Off"

project "cschnorr"
    
    files {"src/**.h", "src/**.c"}

    filter {"platforms:Static"}
        kind "StaticLib"

    filter {"platforms:Shared"}
        kind "SharedLib"

project "test"

    kind "ConsoleApp"
    files {"main.c"}
    links {"cschnorr", "crypto"}
    