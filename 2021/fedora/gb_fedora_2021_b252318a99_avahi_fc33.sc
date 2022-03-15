if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879988" );
	script_version( "2021-08-24T09:58:36+0000" );
	script_cve_id( "CVE-2021-36217" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 09:58:36 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-19 07:17:29 +0000 (Thu, 19 Aug 2021)" );
	script_name( "Fedora: Security Advisory for avahi (FEDORA-2021-b252318a99)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-b252318a99" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DAEY7TOVE45WLMCPR4YIFVLCT43CPTOS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'avahi'
  package(s) announced via the FEDORA-2021-b252318a99 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Avahi is a system which facilitates service discovery on
a local network -- this means that you can plug your laptop or
computer into a network and instantly be able to view other people who
you can chat with, find printers to print to or find files being
shared. This kind of technology is already found in MacOS X (branded
&#39, Rendezvous&#39, , &#39, Bonjour&#39, and sometimes &#39, ZeroConf&#39, ) and is very
convenient." );
	script_tag( name: "affected", value: "'avahi' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "avahi", rpm: "avahi~0.8~14.fc33", rls: "FC33" ) )){
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

