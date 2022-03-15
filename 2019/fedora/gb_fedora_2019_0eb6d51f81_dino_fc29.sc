if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876823" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2019-16235", "CVE-2019-16236", "CVE-2019-16237" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-14 14:26:00 +0000 (Mon, 14 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-09-20 05:35:03 +0000 (Fri, 20 Sep 2019)" );
	script_name( "Fedora Update for dino FEDORA-2019-0eb6d51f81" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-0eb6d51f81" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WZBNQAOBWTIOKNO4PIYNX624ACGUXSXQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dino'
  package(s) announced via the FEDORA-2019-0eb6d51f81 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A modern XMPP ('Jabber') chat client using GTK+/Vala." );
	script_tag( name: "affected", value: "'dino' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "dino", rpm: "dino~0.0~0.12.20190912.git.a96c801.fc29", rls: "FC29" ) )){
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

