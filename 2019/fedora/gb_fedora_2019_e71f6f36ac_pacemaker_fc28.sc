if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875590" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2019-3885", "CVE-2018-16877", "CVE-2018-16878" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-27 18:29:00 +0000 (Mon, 27 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-04 02:10:45 +0000 (Sat, 04 May 2019)" );
	script_name( "Fedora Update for pacemaker FEDORA-2019-e71f6f36ac" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-e71f6f36ac" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3GCWFO7GL6MBU6C4BGFO3P6L77DIBBF3" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'pacemaker' package(s) announced via the FEDORA-2019-e71f6f36ac advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Pacemaker is an advanced, scalable High-Availability
  cluster resource manager for Corosync, CMAN and/or Linux-HA.

It supports more than 16 node clusters with significant capabilities
for managing resources and dependencies.

It will run scripts at initialization, when machines go up or down,
when related resources fail and can be configured to periodically check
resource health.

Available rpmbuild rebuild options:

  - -with(out) : coverage doc hardening pre_release profiling" );
	script_tag( name: "affected", value: "'pacemaker' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "pacemaker", rpm: "pacemaker~1.1.18~3.fc28", rls: "FC28" ) )){
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

