<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use Illuminate\Console\Command;
use CybearCare\LaravelSecurity\Services\DomainVerificationService;

class VerifyDomainCommand extends Command
{
    protected $signature = 'cybear:verify-domain';
    protected $description = 'Verify domain ownership by creating verification file';

    protected DomainVerificationService $verificationService;

    public function __construct(DomainVerificationService $verificationService)
    {
        parent::__construct();
        $this->verificationService = $verificationService;
    }

    public function handle(): int
    {
        $this->info('Starting domain verification process...');
        $this->line('');
        
        $progressBar = $this->output->createProgressBar(4);
        $progressBar->setFormat(' [%bar%] %percent:3s%% - %message%');
        $progressBar->setMessage('Checking domain status...');
        $progressBar->start();
        
        try {
            $progressBar->advance();
            
            $progressBar->setMessage('Requesting verification from Cybear API...');
            $progressBar->advance();
            
            $progressBar->setMessage('Creating verification file...');
            $progressBar->advance();
            
            $progressBar->setMessage('Verifying domain ownership...');
            
            $result = $this->verificationService->autoVerify();
            
            $progressBar->advance();
            $progressBar->finish();
            $this->line('');
            $this->line('');

            if ($result['success']) {
                $this->info($result['message']);
                
                if (($result['status'] ?? '') === 'verified') {
                    $this->info('Cybear Laravel Security is active and ready to use.');
                }
                
                return Command::SUCCESS;
            } else {
                $this->error($result['message']);
                return Command::FAILURE;
            }
        } catch (\Exception $e) {
            $progressBar->finish();
            $this->line('');
            $this->error('Verification failed: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }

}
