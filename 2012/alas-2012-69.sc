if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120593" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:30:16 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-69)" );
	script_tag( name: "insight", value: "Multiple format string vulnerabilities in the error reporting functionality in the YAML::LibYAML (aka YAML-LibYAML and perl-YAML-LibYAML) module 0.38 for Perl allow remote attackers to cause a denial of service (process crash) via format string specifiers in a (1) YAML stream to the Load function, (2) YAML node to the load_node function, (3) YAML mapping to the load_mapping function, or (4) YAML sequence to the load_sequence function." );
	script_tag( name: "solution", value: "Run yum update perl-YAML-LibYAML to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-69.html" );
	script_cve_id( "CVE-2012-1152" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
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
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "perl-YAML-LibYAML-debuginfo", rpm: "perl-YAML-LibYAML-debuginfo~0.38~2.2.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-YAML-LibYAML", rpm: "perl-YAML-LibYAML~0.38~2.2.amzn1", rls: "AMAZON" ) )){
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

