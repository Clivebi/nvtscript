if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120013" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:14:58 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-456)" );
	script_tag( name: "insight", value: "Untrusted search path vulnerability in Puppet Enterprise 2.8 before 2.8.7, Puppet before 2.7.26 and 3.x before 3.6.2, Facter 1.6.x and 2.x before 2.0.2, Hiera before 1.3.4, and Mcollective before 2.5.2, when running with Ruby 1.9.1 or earlier, allows local users to gain privileges via a Trojan horse file in the current working directory, as demonstrated using (1) rubygems/defaults/operating_system.rb, (2) Win32API.rb, (3) Win32API.so, (4) safe_yaml.rb, (5) safe_yaml/deep.rb, or (6) safe_yaml/deep.so or (7) operatingsystem.rb, (8) operatingsystem.so, (9) osfamily.rb, or (10) osfamily.so in puppet/confine." );
	script_tag( name: "solution", value: "Run yum update facter to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-456.html" );
	script_cve_id( "CVE-2014-3248" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "facter", rpm: "facter~1.6.18~7.25.amzn1", rls: "AMAZON" ) )){
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

