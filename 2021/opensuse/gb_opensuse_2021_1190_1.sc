if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854114" );
	script_version( "2021-09-03T08:47:21+0000" );
	script_cve_id( "CVE-2020-14424" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 08:47:21 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-26 03:02:19 +0000 (Thu, 26 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for cacti, (openSUSE-SU-2021:1190-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1190-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YWHMO36YO3PM453SRKAQAGOFPZSA65UT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cacti, '
  package(s) announced via the openSUSE-SU-2021:1190-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cacti, cacti-spine fixes the following issues:

     cacti-spine 1.2.18:

  * Fix missing time parameter on FROM_UNIXTIME function

     cacti 1.2.18:

  * CVE-2020-14424: Lack of escaping on template import can lead to XSS
       exposure under &#x27 midwinter&#x27  theme (boo#1188188)

  * Real time graphs can expose XSS issue" );
	script_tag( name: "affected", value: "'cacti, ' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "cacti-spine", rpm: "cacti-spine~1.2.18~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cacti-spine-debuginfo", rpm: "cacti-spine-debuginfo~1.2.18~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cacti-spine-debugsource", rpm: "cacti-spine-debugsource~1.2.18~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cacti", rpm: "cacti~1.2.18~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
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

