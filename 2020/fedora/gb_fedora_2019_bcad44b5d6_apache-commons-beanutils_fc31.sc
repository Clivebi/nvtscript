if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877152" );
	script_version( "2021-07-16T11:00:51+0000" );
	script_cve_id( "CVE-2019-10086" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-16 11:00:51 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:28:54 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for apache-commons-beanutils FEDORA-2019-bcad44b5d6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-bcad44b5d6" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4APPGLBWMFAS4WHNLR4LIJ65DJGPV7TF" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache-commons-beanutils'
  package(s) announced via the FEDORA-2019-bcad44b5d6 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The scope of this package is to create a package of Java utility methods
for accessing and modifying the properties of arbitrary JavaBeans.  No
dependencies outside of the JDK are required, so the use of this package
is very lightweight." );
	script_tag( name: "affected", value: "'apache-commons-beanutils' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "apache-commons-beanutils", rpm: "apache-commons-beanutils~1.9.4~1.fc31", rls: "FC31" ) )){
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

