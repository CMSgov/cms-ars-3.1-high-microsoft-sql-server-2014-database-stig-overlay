# encoding: utf-8
include_controls 'microsoft-sql-server-2014-database-stig-baseline' do
  control 'V-67357' do
    desc 'Authentication with a CMS-approved PKI certificate does not necessarily 
         imply authorization to access the database and all its contents.  To 
         mitigate the risk of unauthorized access to sensitive information by 
         entities that have been issued certificates by CMS-approved PKIs, all 
         CMS systems, including SQL Server databases, must be properly configured 
         to implement access control policies. 

         Successful authentication must not automatically give an entity access to 
         an asset or security boundary. Authorization procedures and controls must 
         be implemented to ensure each authenticated entity also has a validated 
         and current authorization. Authorization is the process of determining  
         whether an entity, once authenticated, is permitted to access a specific 
         asset. Information systems use access control policies and enforcement 
         mechanisms to implement this requirement. 
         
         Access control policies include identity-based policies, role-based policies,  
         and attribute-based policies. Access enforcement mechanisms include access 
         control lists, access control matrices, and cryptography. These policies 
         and mechanisms must be employed by the application to control access between 
         users (or processes acting on behalf of users) and objects (e.g., devices, 
         files, records, processes, programs, and domains) in the information system.
         
         This requirement is applicable to access control enforcement applications, 
         a category that includes SQL Server.  If SQL Server is not configured to 
         follow applicable policy when approving access, it may be in conflict with 
         networks or other applications in the information system. This may result 
         in users either gaining or being denied access inappropriately and in 
         conflict with applicable policy.'
  end

  control 'V-67361' do
    title 'Where SQL Server Audit is in use at the database level, SQL Server must 
          allow only the ISSO (or individuals or roles appointed by the ISSO) to 
          select which auditable events are to be audited at the database level.'
  end

  control 'V-67365' do
    tag "cci": ['CCI-000345']
    tag "nist": ['CM-5', 'Rev_4']
  end

  control 'V-67367' do
    tag "cci": ['CCI-000345']
    tag "nist": ['CM-5', 'Rev_4']
  end

  control 'V-67369' do
    tag "cci": ['CCI-000345']
    tag "nist": ['CM-5', 'Rev_4']
  end

  control 'V-67371' do
    tag "cci": ['CCI-000345']
    tag "nist": ['CM-5', 'Rev_4']
  end

  control 'V-67373' do
    tag "cci": ['CCI-000345']
    tag "nist": ['CM-5', 'Rev_4']
  end
  
  control 'V-67375' do
    tag "cci": ['CCI-000345']
    tag "nist": ['CM-5', 'Rev_4']
  end

  control 'V-67385' do
    title 'Symmetric keys (other than the database master key) must use a CMS 
          certificate to encrypt the key.'

    desc 'check', 'In a query tool:
         USE <database name>;
         GO
         SELECT s.name, k.crypt_type_desc
         FROM sys.symmetric_keys s, sys.key_encryptions k
         WHERE s.symmetric_key_id = k.key_id
         AND s.name <> \'##MS_DatabaseMasterKey##\'
         AND k.crypt_type IN (\'ESKP\', \'ESKS\')
         ORDER BY s.name, k.crypt_type_desc;
         GO

         Review any symmetric keys that have been defined against the System 
         Security Plan.

         If any keys are defined that are not documented in the System Security 
         Plan, this is a finding.

         Review the System Security Plan to review the encryption mechanism 
         specified for each symmetric key. If the method does not indicate use 
         of certificates, this is a finding.

         If the certificate specified is not a CMS PKI certificate, this is a 
         finding.'
  end

  control 'V-67399' do
    title 'SQL Server must reveal detailed error messages only to the ISSO, SA and DBA.'
  end

  control 'V-67401' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related 
          security control is not mandatory in CMS ARS 3.1'
  end

  control 'V-67403' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related                                                       
          security control is not mandatory in CMS ARS 3.1'
  end

  control 'V-67405' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related                                                       
          security control is not mandatory in CMS ARS 3.1'
  end

  control 'V-67407' do
    title 'Time stamps in database tables, intended for auditing or activity-tracking 
          purposes, must include both date and time of day, with a minimum granularity 
          of one hundred milliseconds (1/10th of a second).'
    desc 'If time stamps are not consistently applied and there is no common time 
         reference, it is difficult to perform forensic analysis, in audit files, trace 
         files/tables, and application data tables.

         Time stamps generated by SQL Server must include date and time, to a granularity 
         of one hundred milliseconds (1/10th of a second) or finer. Time is commonly 
         expressed in Coordinated Universal Time (UTC), a modern continuation of Greenwich 
         Mean Time (GMT), or local time with an offset from UTC. Granularity of time       
         measurements refers to the precision available in time stamp values. Granularity  
         coarser than one second is not sufficient for audit trail purposes, and           
         granularity finer than one second is recommended. Time stamp values are typically 
         presented with three or more decimal places of seconds; however, the actual 
         granularity may be coarser than the apparent precision. For example, SQL Server\'s 
         GETDATE()/CURRENT_TMESTAMP values are presented to three decimal places, but the 
         granularity is not one millisecond: it is about 1/300 of a second. 

         The data types that can be used for this purpose in SQL Server are:
         DATETIME2 - precision variable from a whole second down to a ten-millionth (subject    
         to the actual precision of the hardware and operating system)
         DATETIMEOFFSET - as datetime2, together with local offset from UTC
         DATE, together with TIME (same precision considerations as for datetime2)
         DATETIME - precision 1/10th of a second
         Character-string data types allowing for at least 20 characters are also 
         permissible, but not recommended.

         SQL Server built-in functions for retrieving current timestamps are:  
         (high precision) sysdatetime(), sysdatetimeoffset(), sysutcdatetime();  
         (lower precision) CURRENT_TIMESTAMP or getdate(), getutcdate().

         Ensure that values recorded for tracking purposes in data tables are 
         correctly defined and maintained.  (Design decisions about which tables        
         require audit-trail or activity-tracking columns are outside the scope         
         of this STIG.  This requirement applies only to the data type and              
         maintenance of such columns if they do exist.)

         The SMALLDATETIME data type is not precise enough for this purpose.  
         Although it gives the impression of including a seconds component, the 
         seconds value is always "00".

         SQL Server offers a data type called TIMESTAMP that is not a representation 
         of date and time. Rather, it is a database state counter and does not       
         correspond to calendar and clock time. This requirement does not refer to 
         that meaning of TIMESTAMP.  To avoid confusion, Microsoft recommends using 
         the newer name for this data type, ROWVERSION, instead.'
         desc 'check', 'Review the column definitions and contents of audit-trail
              and activity-tracking timestamps in database tables.

              If these are not defined and maintained to include date and time of day, 
              accurate to a granularity of one hundred milliseconds (1/10th of a second) 
              or finer, this is a finding.'
         desc 'fix', 'Modify applications and/or column/field definitions so that the 
              time stamps in audit-trail and activity-tracking columns/fields in 
              application data include date and time of day, to a granularity of one 
              hundred milliseconds (1/10th of a second) or finer, and are recorded 
              accurately.'
  end

  control 'V-67409' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related                                                       
          security control is not mandatory in CMS ARS 3.1'
  end

  control 'V-67411' do  
    tag "cci": ['CCI-001310']
    tag "nist": ['SI-10', 'Rev_4']
  end
end
