if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876748" );
	script_version( "2021-09-01T14:01:32+0000" );
	script_cve_id( "CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516", "CVE-2018-16845", "CVE-2018-16843", "CVE-2018-16844" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 14:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-30 02:36:00 +0000 (Sat, 30 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-09-05 02:25:48 +0000 (Thu, 05 Sep 2019)" );
	script_name( "Fedora Update for nginx FEDORA-2019-7a0b45fdc4" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-7a0b45fdc4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/POPAEC4FWL4UU4LDEGPY5NPALU24FFQD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nginx'
  package(s) announced via the FEDORA-2019-7a0b45fdc4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Nginx is a web server and a reverse proxy server for HTTP, SMTP, POP3 and
IMAP protocols, with a strong focus on high concurrency, performance and low
memory usage." );
	script_tag( name: "affected", value: "'nginx' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "nginx", rpm: "nginx~1.16.1~1.fc29", rls: "FC29" ) )){
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

