if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876723" );
	script_version( "2021-09-01T14:01:32+0000" );
	script_cve_id( "CVE-2019-13509" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-27 17:15:00 +0000 (Tue, 27 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-08-29 02:25:04 +0000 (Thu, 29 Aug 2019)" );
	script_name( "Fedora Update for docker FEDORA-2019-5b54793a4a" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-5b54793a4a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PFFBVE7O73TAVY2BCWXSA2OOSLJVCPXC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'docker'
  package(s) announced via the FEDORA-2019-5b54793a4a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Docker is an open-source engine that automates the deployment of any
application as a lightweight, portable, self-sufficient container that will
run virtually anywhere.

Docker containers can encapsulate any payload, and will run consistently on
and between virtually any server. The same container that a developer builds
and tests on a laptop will run at scale, in production*, on VMs, bare-metal
servers, OpenStack clusters, public instances, or combinations of the above." );
	script_tag( name: "affected", value: "'docker' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "docker", rpm: "docker~1.13.1~68.git47e2230.fc30", rls: "FC30" ) )){
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

