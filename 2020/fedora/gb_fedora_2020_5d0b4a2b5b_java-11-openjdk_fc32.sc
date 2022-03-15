if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878126" );
	script_version( "2021-07-13T11:00:50+0000" );
	script_cve_id( "CVE-2020-14562", "CVE-2020-14573", "CVE-2020-14556", "CVE-2020-14577", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-13 11:00:50 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-10 16:15:00 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-07-24 03:09:07 +0000 (Fri, 24 Jul 2020)" );
	script_name( "Fedora: Security Advisory for java-11-openjdk (FEDORA-2020-5d0b4a2b5b)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-5d0b4a2b5b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QQUMIAON2YEFRONMIUVHAKYCIOLICDBA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-11-openjdk'
  package(s) announced via the FEDORA-2020-5d0b4a2b5b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenJDK runtime environment." );
	script_tag( name: "affected", value: "'java-11-openjdk' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk", rpm: "java-11-openjdk~11.0.8.10~2.fc32", rls: "FC32" ) )){
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

