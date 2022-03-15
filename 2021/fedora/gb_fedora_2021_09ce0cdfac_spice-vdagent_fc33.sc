if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878928" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2020-25650", "CVE-2020-25651", "CVE-2020-25652", "CVE-2020-25653" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 17:38:00 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-12 04:02:09 +0000 (Fri, 12 Feb 2021)" );
	script_name( "Fedora: Security Advisory for spice-vdagent (FEDORA-2021-09ce0cdfac)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-09ce0cdfac" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OIWJ2EIQXWEA2VDBODEATHAT37X4CREP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-vdagent'
  package(s) announced via the FEDORA-2021-09ce0cdfac advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Spice agent for Linux guests offering the following features:

Features:

  * Client mouse mode (no need to grab mouse by client, no mouse lag)
  this is handled by the daemon by feeding mouse events into the kernel
  via uinput. This will only work if the active X-session is running a
  spice-vdagent process so that its resolution can be determined.

  * Automatic adjustment of the X-session resolution to the client resolution

  * Support of copy and paste (text and images) between the active X-session
  and the client" );
	script_tag( name: "affected", value: "'spice-vdagent' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "spice-vdagent", rpm: "spice-vdagent~0.21.0~1.fc33", rls: "FC33" ) )){
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

