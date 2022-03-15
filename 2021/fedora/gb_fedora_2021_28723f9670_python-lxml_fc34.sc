if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879701" );
	script_version( "2021-08-23T14:00:58+0000" );
	script_cve_id( "CVE-2021-28957" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 14:00:58 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-04 04:15:00 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-03 06:24:46 +0000 (Thu, 03 Jun 2021)" );
	script_name( "Fedora: Security Advisory for python-lxml (FEDORA-2021-28723f9670)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-28723f9670" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3C2R44VDUY7FJVMAVRZ2WY7XYL4SVN45" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-lxml'
  package(s) announced via the FEDORA-2021-28723f9670 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "lxml is a Pythonic, mature binding for the libxml2 and libxslt libraries. It
provides safe and convenient access to these libraries using the ElementTree It
extends the ElementTree API significantly to offer support for XPath, RelaxNG,
XML Schema, XSLT, C14N and much more.To contact the project, go to the project
home page < or see our bug tracker at case you want to use the current" );
	script_tag( name: "affected", value: "'python-lxml' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "python-lxml", rpm: "python-lxml~4.6.3~1.fc34", rls: "FC34" ) )){
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

