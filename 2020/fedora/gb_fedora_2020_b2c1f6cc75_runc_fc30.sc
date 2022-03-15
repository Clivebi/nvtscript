if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877447" );
	script_version( "2021-07-14T11:00:55+0000" );
	script_cve_id( "CVE-2019-19921", "CVE-2019-16884" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-14 11:00:55 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-08 03:15:00 +0000 (Tue, 08 Oct 2019)" );
	script_tag( name: "creation_date", value: "2020-02-08 04:04:33 +0000 (Sat, 08 Feb 2020)" );
	script_name( "Fedora: Security Advisory for runc (FEDORA-2020-b2c1f6cc75)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2020-b2c1f6cc75" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2NWDTSREUDLT3UFYS5SBIVQBS4YRA35A" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'runc'
  package(s) announced via the FEDORA-2020-b2c1f6cc75 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The runc command can be used to start containers which are packaged
in accordance with the Open Container Initiative&#39, s specifications,
and to manage containers running under runc." );
	script_tag( name: "affected", value: "'runc' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "runc", rpm: "runc~1.0.0~102.dev.gitdc9208a.fc30", rls: "FC30" ) )){
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

