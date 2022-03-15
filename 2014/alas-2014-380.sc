if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120402" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:25:33 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-380)" );
	script_tag( name: "insight", value: "It was reported that Python built-in _json module have a flaw (insufficient bounds checking), which allows a local user to read current process's arbitrary memory.Quoting the upstream bug report:The sole prerequisites of this attack are that the attacker is able to control or influence the two parameters of the default scanstring function: the string to be decoded and the index.The bug is caused by allowing the user to supply a negative index value. The index value is then used directly as an index to an array in the C code. Internally the address of the array and its index are added to each other in order to yield the address of the value that is desired. However, by supplying a negative index value and adding this to the address of the array, the processor's register value wraps around and the calculated value will point to a position in memory which isn't within the bounds of the supplied string, causing the function to access other parts of the process memory." );
	script_tag( name: "solution", value: "Run yum update python27 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-380.html" );
	script_cve_id( "CVE-2014-4616" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
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
	if(!isnull( res = isrpmvuln( pkg: "python27-tools", rpm: "python27-tools~2.7.5~13.35.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python27", rpm: "python27~2.7.5~13.35.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python27-test", rpm: "python27-test~2.7.5~13.35.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python27-debuginfo", rpm: "python27-debuginfo~2.7.5~13.35.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python27-libs", rpm: "python27-libs~2.7.5~13.35.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python27-devel", rpm: "python27-devel~2.7.5~13.35.amzn1", rls: "AMAZON" ) )){
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

