if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879054" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2020-29074" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-25 00:01:00 +0000 (Thu, 25 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 10:40:10 +0000 (Wed, 10 Mar 2021)" );
	script_name( "Fedora: Security Advisory for x11vnc (FEDORA-2021-c5b679877e)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-c5b679877e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MHVXHZE3YIP4RTWGQ24IDBSW44XPRDOC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'x11vnc'
  package(s) announced via the FEDORA-2021-c5b679877e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "What WinVNC is to Windows x11vnc is to X Window System, i.e. a server which
serves the current X Window System desktop via RFB (VNC) protocol to the user.

Based on the ideas of x0rfbserver and on LibVNCServer it has evolved into
a versatile and productive while still easy to use program." );
	script_tag( name: "affected", value: "'x11vnc' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "x11vnc", rpm: "x11vnc~0.9.16~3.fc32", rls: "FC32" ) )){
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

