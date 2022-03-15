if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878773" );
	script_version( "2021-08-20T14:00:58+0000" );
	script_cve_id( "CVE-2020-26892", "CVE-2020-26521" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:00:58 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 03:15:00 +0000 (Mon, 04 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-11 10:58:50 +0000 (Mon, 11 Jan 2021)" );
	script_name( "Fedora: Security Advisory for nats-server (FEDORA-2020-2c8851d48b)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-2c8851d48b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VT67XCLIIBYRT762SVFBYFFTQFVSM3SI" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nats-server'
  package(s) announced via the FEDORA-2020-2c8851d48b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A High Performance NATS Server written in Go and hosted by the Cloud Native
Computing Foundation (CNCF)." );
	script_tag( name: "affected", value: "'nats-server' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "nats-server", rpm: "nats-server~2.1.9~1.fc33", rls: "FC33" ) )){
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

