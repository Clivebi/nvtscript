if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878847" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2020-28049" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-28 18:53:00 +0000 (Thu, 28 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-25 04:01:12 +0000 (Mon, 25 Jan 2021)" );
	script_name( "Fedora: Security Advisory for sddm (FEDORA-2021-7066b95c99)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2021-7066b95c99" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GT3EX5NSQJJAKY63ENSMEDX6NYZLYY3S" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sddm'
  package(s) announced via the FEDORA-2021-7066b95c99 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "SDDM is a modern display manager for X11 aiming to be fast, simple and
beautiful. It uses modern technologies like QtQuick, which in turn gives the
designer the ability to create smooth, animated user interfaces." );
	script_tag( name: "affected", value: "'sddm' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "sddm", rpm: "sddm~0.19.0~3.fc33", rls: "FC33" ) )){
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

