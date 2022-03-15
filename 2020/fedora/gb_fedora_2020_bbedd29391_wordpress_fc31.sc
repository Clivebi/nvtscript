if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877997" );
	script_version( "2021-07-13T11:00:50+0000" );
	script_cve_id( "CVE-2020-4046", "CVE-2020-4047", "CVE-2020-4048", "CVE-2020-4049", "CVE-2020-4050" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 11:00:50 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-11 17:15:00 +0000 (Fri, 11 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-06-23 03:20:41 +0000 (Tue, 23 Jun 2020)" );
	script_name( "Fedora: Security Advisory for wordpress (FEDORA-2020-bbedd29391)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-bbedd29391" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/773N2ZV7QEMBGKH6FBKI6Q5S3YJMW357" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wordpress'
  package(s) announced via the FEDORA-2020-bbedd29391 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Wordpress is an online publishing / weblog package that makes it very easy,
almost trivial, to get information out to people on the web.

Important information in /usr/share/doc/wordpress/README.fedora" );
	script_tag( name: "affected", value: "'wordpress' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "wordpress", rpm: "wordpress~5.4.2~1.fc31", rls: "FC31" ) )){
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

