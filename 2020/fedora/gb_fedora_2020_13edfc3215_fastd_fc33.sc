if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878554" );
	script_version( "2021-07-16T02:00:53+0000" );
	script_cve_id( "CVE-2020-27638" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-16 02:00:53 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-03 03:15:00 +0000 (Tue, 03 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:24:00 +0000 (Tue, 03 Nov 2020)" );
	script_name( "Fedora: Security Advisory for fastd (FEDORA-2020-13edfc3215)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-13edfc3215" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/D2LNSF2LI4RQ7BVGHTJQUJWP7RVGHDTK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fastd'
  package(s) announced via the FEDORA-2020-13edfc3215 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "fastd is a secure tunneling daemon with some unique features:

  - Very small binary (about 100KB on OpenWRT in the default configuration,
   including all dependencies besides libc)

  - Exchangeable crypto methods

  - Transport over UDP for simple usage behind NAT

  - Can run in 1:1 and 1:n scenarios

  - There are no server and client roles defined by the protocol, this is just
   defined by the usage.

  - Only one instance of the daemon is needed on each host to create a full mesh
   If no full mesh is established, a routing protocol is necessary to enable
   hosts that are not connected directly to reach each other" );
	script_tag( name: "affected", value: "'fastd' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "fastd", rpm: "fastd~21~1.fc33", rls: "FC33" ) )){
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

