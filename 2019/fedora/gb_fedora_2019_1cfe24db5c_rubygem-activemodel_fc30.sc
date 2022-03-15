if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876341" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-5418", "CVE-2019-5419", "CVE-2019-5420" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 19:02:00 +0000 (Fri, 16 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-05-10 02:11:32 +0000 (Fri, 10 May 2019)" );
	script_name( "Fedora Update for rubygem-activemodel FEDORA-2019-1cfe24db5c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-1cfe24db5c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Y43636TH4D6T46IC6N2RQVJTRFJAAYGA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'rubygem-activemodel' package(s) announced via the FEDORA-2019-1cfe24db5c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "A toolkit for building modeling frameworks
  like Active Record. Rich support for attributes, callbacks, validations,
  serialization, internationalization, and testing." );
	script_tag( name: "affected", value: "'rubygem-activemodel' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activemodel", rpm: "rubygem-activemodel~5.2.3~2.fc30", rls: "FC30" ) )){
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

