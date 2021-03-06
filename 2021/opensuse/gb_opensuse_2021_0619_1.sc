if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853780" );
	script_version( "2021-04-30T07:59:33+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-30 07:59:33 +0000 (Fri, 30 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-27 03:02:09 +0000 (Tue, 27 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for libdwarf (openSUSE-SU-2021:0619-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0619-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XUNO6MM3ADPC66KJBAHXCEBKHQ5PERD6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libdwarf'
  package(s) announced via the openSUSE-SU-2021:0619-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libdwarf fixes the following issues:

  - Hardening: Link /usr/bin/dwarfdump as PIE (bsc#1185057).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'libdwarf' package(s) on openSUSE Leap 15.2." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "libdwarf-debuginfo", rpm: "libdwarf-debuginfo~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdwarf-debugsource", rpm: "libdwarf-debugsource~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdwarf-devel", rpm: "libdwarf-devel~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdwarf-devel-debuginfo", rpm: "libdwarf-devel-debuginfo~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdwarf-devel-static", rpm: "libdwarf-devel-static~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdwarf-doc", rpm: "libdwarf-doc~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdwarf-tools", rpm: "libdwarf-tools~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdwarf-tools-debuginfo", rpm: "libdwarf-tools-debuginfo~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdwarf1", rpm: "libdwarf1~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdwarf1-debuginfo", rpm: "libdwarf1-debuginfo~20161124~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

