if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120403" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:25:34 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-381)" );
	script_tag( name: "insight", value: "Multiple cross-site scripting (XSS) vulnerabilities in Cacti 0.8.8b allow remote attackers to inject arbitrary web script or HTML via the (1) drp_action parameter to cdef.php, (2) data_input.php, (3) data_queries.php, (4) data_sources.php, (5) data_templates.php, (6) graph_templates.php, (7) graphs.php, (8) host.php, or (9) host_templates.php or the (10) graph_template_input_id or (11) graph_template_id parameter to graph_templates_inputs.php." );
	script_tag( name: "solution", value: "Run yum update cacti to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-381.html" );
	script_cve_id( "CVE-2014-4002" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
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
	if(!isnull( res = isrpmvuln( pkg: "cacti", rpm: "cacti~0.8.8b~7.5.amzn1", rls: "AMAZON" ) )){
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

