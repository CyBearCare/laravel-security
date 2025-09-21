<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use Illuminate\Console\Command;
use CybearCare\LaravelSecurity\Services\DomainVerificationService;
use Illuminate\Support\Facades\Log;

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

        $result = $this->verificationService->autoVerify();

        if ($result['success']) {
            $this->info($result['message']);
            
            if (($result['status'] ?? '') === 'verified') {
                $this->info('🎉 Cybear Laravel Security is now active and ready to use!');
            }
            
            return Command::SUCCESS;
        } else {
            $this->error($result['message']);
            return Command::FAILURE;
        }
    }

}