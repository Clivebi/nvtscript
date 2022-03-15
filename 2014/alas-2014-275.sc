if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120567" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:29:43 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-275)" );
	script_tag( name: "insight", value: "The get_group_tree function in lib/Munin/Master/HTMLConfig.pm in Munin before 2.0.18 allows remote nodes to cause a denial of service (infinite loop and memory consumption in the munin-html process) via crafted multigraph data. Munin::Master::Node in Munin before 2.0.18 allows remote attackers to cause a denial of service (abort data collection for node) via a plugin that uses multigraph as a multigraph service name." );
	script_tag( name: "solution", value: "Run yum update munin to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-275.html" );
	script_cve_id( "CVE-2013-6048", "CVE-2013-6359" );
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
	if(!isnull( res = isrpmvuln( pkg: "munin-cgi", rpm: "munin-cgi~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "munin-common", rpm: "munin-common~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "munin-node", rpm: "munin-node~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "munin-nginx", rpm: "munin-nginx~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "munin-netip-plugins", rpm: "munin-netip-plugins~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "munin", rpm: "munin~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "munin-java-plugins", rpm: "munin-java-plugins~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "munin-async", rpm: "munin-async~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "munin-ruby-plugins", rpm: "munin-ruby-plugins~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "munin", rpm: "munin~2.0.19~1.32.amzn1", rls: "AMAZON" ) )){
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

