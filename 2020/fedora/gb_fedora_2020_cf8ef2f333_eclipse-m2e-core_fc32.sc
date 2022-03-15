if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878244" );
	script_version( "2021-07-21T02:01:11+0000" );
	script_cve_id( "CVE-2019-17566", "CVE-2019-17638" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:51:41 +0530 (Wed, 02 Sep 2020)" );
	script_name( "Fedora: Security Advisory for eclipse-m2e-core (FEDORA-2020-cf8ef2f333)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-cf8ef2f333" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4KSWIWOCHSM44NPNJXPEMVWUP4MNY4SL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'eclipse-m2e-core'
  package(s) announced via the FEDORA-2020-cf8ef2f333 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The goal of the m2ec project is to provide a first-class Apache Maven support
in the Eclipse IDE, making it easier to edit Maven&#39, s pom.xml, run a build from
the IDE and much more. For Java developers, the very tight integration with JDT
greatly simplifies the consumption of Java artifacts either being hosted on open
source repositories such as Maven Central, or in your in-house Maven repository.

m2e is also a platform that let others provide better integration with
additional Maven plugins (e.g. Android, web development, etc.), and facilitates
the distribution of those extensions through the m2e marketplace." );
	script_tag( name: "affected", value: "'eclipse-m2e-core' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "eclipse-m2e-core", rpm: "eclipse-m2e-core~1.16.1~1.fc32", rls: "FC32" ) )){
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

