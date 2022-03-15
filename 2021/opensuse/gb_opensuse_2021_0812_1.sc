if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853840" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-27819" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-26 17:30:00 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-06-01 03:01:10 +0000 (Tue, 01 Jun 2021)" );
	script_name( "openSUSE: Security Advisory for libxls (openSUSE-SU-2021:0812-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0812-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G6PICHOKDDWFUM2A34VZUNW6XR4NUUPC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxls'
  package(s) announced via the openSUSE-SU-2021:0812-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libxls fixes the following issues:

     libxsl was updated to release 1.6.2:

  * Fix NULL pointer dereferences in the xls2csv tool [boo#1179532]
       [CVE-2020-27819]

     Update to release 1.6.1

  * Enabled decoding of non-Unicode character sets in older (BIFF5) XLS
       files.

  * Improved string conversion performance in newer files.

     update to 1.5.3:

  * Allow truncated XLS files

  * Fix long-standing 'extra column' bug #73

  * Support for RSTRING records (rich-text cells in older BIFF5 files)
       tidyverse/readxl#611" );
	script_tag( name: "affected", value: "'libxls' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libxls-debuginfo", rpm: "libxls-debuginfo~1.6.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxls-debugsource", rpm: "libxls-debugsource~1.6.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxls-devel", rpm: "libxls-devel~1.6.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxls-tools", rpm: "libxls-tools~1.6.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxls-tools-debuginfo", rpm: "libxls-tools-debuginfo~1.6.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxlsreader8", rpm: "libxlsreader8~1.6.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxlsreader8-debuginfo", rpm: "libxlsreader8-debuginfo~1.6.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

